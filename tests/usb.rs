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
                hp.install,
                hp.first_install,
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
