//! USB history in regipy's test data (MIT; `tests/fixtures/regipy/`): the `SYSTEM` and
//! `NTUSER.DAT` hives of one Windows 7 computer. The device and its times are those regipy's
//! `usb_devices` and Plaso's `windows_usbstor_devices` read (Plaso reads the Windows 7 layout of
//! the times; regipy doesn't), the `MountedDevices` values those of regipy's
//! `mounted_devices`, and the `MountPoints2` keys those of Plaso's `explorer_mountpoints2`.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::usb::{self, DeviceClass, MountTarget, Sources};

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

/// 2011-04-01T05:32:38.686Z: the HP drive's install time, as Plaso reads it.
const INSTALLED: u64 = 129_461_071_586_860_000;

#[test]
fn devices_and_their_windows_7_times() {
    let system = fixture("SYSTEM");
    for set in [1, 2] {
        let (devices, problems) = usb::devices(&system, set).unwrap();
        assert_eq!(problems, Vec::<String>::new());
        let classes: Vec<_> = devices.iter().map(|d| d.class).collect();
        assert_eq!(
            classes
                .iter()
                .filter(|&&c| c == DeviceClass::UsbStorage)
                .count(),
            1
        );
        assert_eq!(
            classes.iter().filter(|&&c| c == DeviceClass::Usb).count(),
            7
        );
        let hp = &devices[0];
        assert_eq!(
            hp.path,
            format!(
                r"ControlSet00{set}\Enum\USBSTOR\Disk&Ven_HP&Prod_v100w&Rev_1024\AA951D0000007252&0"
            )
        );
        assert_eq!(
            (
                hp.kind.as_deref(),
                hp.vendor.as_deref(),
                hp.product.as_deref(),
                hp.revision.as_deref(),
                hp.serial.as_deref(),
                hp.friendly_name.as_deref(),
            ),
            (
                Some("Disk"),
                Some("HP"),
                Some("v100w"),
                Some("1024"),
                Some("AA951D0000007252"),
                Some("HP v100w USB Device")
            )
        );
        assert_eq!(
            (
                hp.driver_last_installed,
                hp.device_first_install,
                hp.last_arrival,
                hp.last_removal
            ),
            (Some(INSTALLED), Some(INSTALLED), None, None)
        );
        assert!(hp.problems.is_empty() && !hp.replayed);
    }
}

#[test]
fn volumes_letters_and_the_user_who_mounted_them() {
    let system = fixture("SYSTEM");
    let (mounted, problems) = usb::mounted_devices(&system).unwrap();
    assert_eq!((mounted.len(), problems.len()), (11, 0));
    let c = mounted
        .iter()
        .find(|m| m.drive_letter == Some('C'))
        .unwrap();
    assert_eq!(
        c.target,
        MountTarget::Mbr {
            signature: 0x5cbe_a03e,
            offset: 1_048_576
        }
    );
    let (points, problems) = usb::mount_points(&fixture("NTUSER.DAT")).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    let names: Vec<_> = points.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "##controller#public",
            "CPC",
            "{656b1715-ecf6-11df-92e6-806e6f6e6963}",
            "{656b1718-ecf6-11df-92e6-806e6f6e6963}"
        ]
    );
    let devices = usb::devices(&system, 1).unwrap().0;
    let users = vec![("user".to_owned(), points)];
    let history = usb::history(&Sources {
        devices: &devices,
        mounted: &mounted,
        users: &users,
        ..Sources::default()
    });
    // the HP drive's volume was last E:
    let hp = &history[0];
    assert_eq!(
        (
            hp.volume_guid.as_deref(),
            hp.drive_letters.as_slice(),
            hp.found_in.as_slice()
        ),
        (
            Some("{eba74da6-5bb2-11e0-95d1-000c2971073c}"),
            &['E'][..],
            &["Enum", "MountedDevices"][..]
        )
    );
    // C: and D:, mounted by the user
    let volumes: Vec<_> = history
        .iter()
        .filter(|h| h.device.is_none() && !h.users.is_empty())
        .map(|h| (h.drive_letters.clone(), h.users[0].user.as_str()))
        .collect();
    assert_eq!(volumes, [(vec!['C'], "user"), (vec!['D'], "user")]);
    // 8 devices (one with a volume), then 6 volumes no device has
    assert_eq!(history.len(), 14);
}

fn identity_devices() -> (usb::Device, usb::Device) {
    let hive = fixture("SYSTEM");
    let devices = usb::devices(&hive, 1).unwrap().0;
    let mut storage = devices
        .iter()
        .find(|d| d.class == DeviceClass::UsbStorage)
        .unwrap()
        .clone();
    let mut usb = devices
        .iter()
        .find(|d| d.class == DeviceClass::Usb && d.vid.is_some())
        .unwrap()
        .clone();
    storage.serial = Some("SERIAL".into());
    usb.serial = Some("SERIAL".into());
    storage.container_id = Some("{aaaaaaaa-0000-0000-0000-000000000001}".into());
    usb.container_id.clone_from(&storage.container_id);
    storage.replayed = false;
    usb.replayed = true;
    (storage, usb)
}
fn identity_history(devices: &[usb::Device]) -> usb::History {
    usb::history(&Sources {
        devices,
        mounted: &[],
        portable: &[],
        ready_boost: &[],
        users: &[],
    })
    .into_iter()
    .find(|h| {
        h.device
            .as_ref()
            .is_some_and(|d| d.class == DeviceClass::UsbStorage)
    })
    .unwrap()
}
#[test]
fn usb_identity_never_uses_a_conflicting_container_or_ambiguous_ids() {
    let (storage, mut usb) = identity_devices();
    usb.container_id = Some("{bbbbbbbb-0000-0000-0000-000000000002}".into());
    assert!(
        identity_history(&[storage.clone(), usb.clone()])
            .vid_pid
            .is_none()
    );
    usb.container_id.clone_from(&storage.container_id);
    let mut other = usb.clone();
    other.vid = Some("FFFF".into());
    other.pid = Some("EEEE".into());
    assert!(identity_history(&[storage, usb, other]).vid_pid.is_none());
}
#[test]
fn usb_identity_keeps_the_contributing_key_and_replay_provenance() {
    let (storage, usb) = identity_devices();
    let history = identity_history(&[storage, usb.clone()]);
    assert_eq!(history.vid_pid, Some((usb.vid, usb.pid)));
    assert!(history.keys.contains(&format!("SYSTEM {}", usb.path)));
    assert!(history.replayed_in.contains(&"SYSTEM"));
}

#[test]
fn usb_identity_serial_fallback_is_unique_and_control_set_scoped() {
    let (mut storage, mut usb) = identity_devices();
    storage.container_id = None;
    let expected = Some((usb.vid.clone(), usb.pid.clone()));
    assert_eq!(
        identity_history(&[storage.clone(), usb.clone()]).vid_pid,
        expected
    );
    let mut duplicate = usb.clone();
    duplicate.vid = Some("FFFF".into());
    duplicate.pid = Some("EEEE".into());
    assert!(
        identity_history(&[storage.clone(), usb.clone(), duplicate.clone()])
            .vid_pid
            .is_none()
    );
    duplicate.control_set = 2;
    assert_eq!(
        identity_history(&[storage.clone(), usb.clone(), duplicate]).vid_pid,
        expected
    );
    usb.control_set = 2;
    assert!(identity_history(&[storage, usb]).vid_pid.is_none());
}

#[test]
fn portable_names_do_not_cross_control_sets_and_retain_their_source() {
    let (storage, mut usb) = identity_devices();
    usb.replayed = false;
    let mut portable = storage.clone();
    portable.class = DeviceClass::PortableDevice;
    portable.path = r"ControlSet001\Enum\SWD\WPDBUSENUM\current".into();
    portable.friendly_name = Some("Current label".into());
    portable.replayed = true;
    let mut old = portable.clone();
    old.control_set = 2;
    old.path = r"ControlSet002\Enum\SWD\WPDBUSENUM\old".into();
    old.friendly_name = Some("Historical label".into());
    let history = identity_history(&[storage, usb, portable.clone(), old.clone()]);
    assert_eq!(history.volume_names, ["Current label"]);
    assert!(history.keys.contains(&format!("SYSTEM {}", portable.path)));
    assert!(!history.keys.contains(&format!("SYSTEM {}", old.path)));
    assert!(history.replayed_in.contains(&"SYSTEM"));
}
