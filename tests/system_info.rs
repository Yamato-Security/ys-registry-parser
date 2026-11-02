//! What regipy's test hives (MIT; `tests/fixtures/regipy/`) say about their systems: its Windows 7
//! `SYSTEM`, its `SAM` and its `SECURITY` (three different systems). Every field is what regipy's
//! `computer_name`, `host_domain_name`, `timezone_data2`, `shutdown`, `processor_architecture`,
//! `local_sid` and `domain_sid` plugins give for the same hives, and the time zone's changes are
//! those of the zone's `TZI` in a `SOFTWARE` hive.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::system_info::{domains, machine_sid, system, utc_offset};

fn fixture(name: &str) -> Hive {
    let path = format!(
        "{}/tests/fixtures/regipy/{name}.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    Hive::open(data, &[]).unwrap().0
}

#[test]
fn a_windows_7_system() {
    let found = system(&fixture("SYSTEM"));
    assert_eq!(found.problems, Vec::<String>::new());
    assert_eq!((found.control_set, found.is_current), (Some(1), true));
    assert_eq!(found.computer_name.as_deref(), Some("WKS-WIN732BITA"));
    assert_eq!(
        found.computer_name_last_written,
        Some(129_338_830_887_187_500)
    );
    assert_eq!(found.hostname.as_deref(), Some("WKS-WIN732BITA"));
    assert_eq!(found.domain.as_deref(), Some("shieldbase.local"));
    assert_eq!(found.last_shutdown, Some(129_779_783_208_392_499));
    assert_eq!(found.processor_architecture.as_deref(), Some("x86"));
    assert_eq!(
        (
            found.ansi_code_page.as_deref(),
            found.oem_code_page.as_deref()
        ),
        (Some("1252"), Some("437"))
    );
    assert!(found.previous_versions.is_empty() && !found.replayed);

    let zone = found.time_zone.unwrap();
    // TimeZoneKeyName has bytes past its NUL: read up to it, as Windows does
    assert_eq!(zone.name(), Some("Eastern Standard Time"));
    assert_eq!(
        (zone.standard_name.as_deref(), zone.daylight_name.as_deref()),
        (Some("@tzres.dll,-112"), Some("@tzres.dll,-111"))
    );
    assert_eq!(
        (
            zone.bias,
            zone.standard_bias,
            zone.daylight_bias,
            zone.active_time_bias
        ),
        (Some(300), Some(0), Some(-60), Some(240))
    );
    assert_eq!(utc_offset(zone.bias.unwrap()), "UTC-05:00");
    // written in daylight time
    assert_eq!(utc_offset(zone.active_time_bias.unwrap()), "UTC-04:00");
    assert_eq!(
        zone.standard_start.and_then(|d| d.describe()).as_deref(),
        Some("first Sunday of November, 02:00")
    );
    assert_eq!(
        zone.daylight_start.and_then(|d| d.describe()).as_deref(),
        Some("second Sunday of March, 02:00")
    );
    assert_eq!(zone.dynamic_daylight_time_disabled, Some(false));
    assert_eq!(zone.real_time_is_universal, None);
    assert_eq!(zone.key_last_written, 129_759_228_000_006_424);
    assert_eq!(zone.key_path, r"ControlSet001\Control\TimeZoneInformation");
}

#[test]
fn the_sids_of_a_sam_and_a_security_hive() {
    assert_eq!(
        machine_sid(&fixture("SAM")).as_deref(),
        Some("S-1-5-21-1760460187-1592185332-161725925")
    );
    // a SYSTEM hive has no SAM\Domains\Account, and no Policy
    let system = fixture("SYSTEM");
    assert_eq!(machine_sid(&system), None);
    assert!(domains(&system).is_none());

    let found = domains(&fixture("SECURITY")).unwrap();
    assert_eq!(found.problems, Vec::<String>::new());
    assert_eq!(
        found.account_domain_name.as_deref(),
        Some("DESKTOP-M964FJN")
    );
    assert_eq!(
        found.account_domain_sid.as_deref(),
        Some("S-1-5-21-1786693902-1815088602-2777321892")
    );
    // a workgroup: no domain SID, DNS names, GUID or computer account
    assert_eq!(found.primary_domain_name.as_deref(), Some("WORKGROUP"));
    assert_eq!(
        found.primary_domain_last_written,
        Some(132_726_338_195_059_112)
    );
    assert_eq!(
        (
            &found.primary_domain_sid,
            &found.dns_domain_name,
            &found.dns_forest_name,
            &found.domain_guid,
            &found.machine_account_sid
        ),
        (&None, &None, &None, &None, &None)
    );
}
