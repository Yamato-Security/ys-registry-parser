//! regipy's `BCD` (MIT; `tests/fixtures/regipy/`): a Windows 10 UEFI store whose boot entries
//! regipy's `boot_entry_list` reads with the same descriptions, paths and partition GUIDs.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::Hive;
use ys_registry_parser::bcd::{BcdObject, BcdValue, bcd};

fn store() -> Vec<BcdObject> {
    let path = format!(
        "{}/tests/fixtures/regipy/BCD.gz",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut data = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    let hive = Hive::open(data, &[]).unwrap().0;
    let (objects, problems) = bcd(&hive).unwrap();
    assert_eq!(problems, Vec::<String>::new());
    objects
}

fn find<'a>(objects: &'a [BcdObject], guid: &str) -> &'a BcdObject {
    objects.iter().find(|o| o.guid == guid).unwrap()
}

#[test]
fn a_windows_10_store() {
    let objects = store();
    assert_eq!(objects.len(), 17);
    assert!(objects.iter().all(|o| o.problems.is_empty() && !o.replayed));
    assert_eq!(objects.iter().map(|o| o.elements.len()).sum::<usize>(), 78);
    // the boot manager's default entry, first in its display order
    let windows = find(&objects, "{733b62e5-f608-11eb-825c-c112f60133ab}");
    assert_eq!(
        (
            windows.object_type,
            windows.type_name.as_str(),
            windows.description.as_deref(),
            windows.is_default,
            windows.display_order,
            windows.path.as_deref(),
            windows.device.as_deref(),
        ),
        (
            Some(0x1020_0003),
            "Windows boot loader",
            Some("Windows 10"),
            true,
            Some(0),
            Some(r"\Windows\system32\winload.efi"),
            Some(
                "partition {8e0f2c38-e4ea-47ba-b7fc-9d8c74dccf0b} on disk {0b2394a9-095e-487d-8d48-719ecd4d78ca}"
            ),
        )
    );
    assert_eq!(
        (
            windows.recovery_enabled,
            windows.test_signing,
            windows.no_integrity_checks,
            windows.safe_boot,
            windows.boot_status_policy
        ),
        (Some(true), None, None, None, None)
    );
    assert_eq!(windows.inherited, Vec::<String>::new());
    let recovery = windows
        .elements
        .iter()
        .find(|e| e.element_type == Some(0x1600_0009))
        .unwrap();
    assert_eq!(
        (recovery.name, &recovery.value, recovery.key_last_written),
        (
            Some("BcdLibraryBoolean_AutoRecoveryEnabled"),
            &BcdValue::Boolean(true),
            132_726_339_843_087_097
        )
    );
    // an element type Microsoft doesn't document keeps its bytes
    let undocumented = windows
        .elements
        .iter()
        .find(|e| e.key_name == "15000066")
        .unwrap();
    assert_eq!(
        (
            undocumented.name,
            &undocumented.value,
            undocumented.data_raw.as_deref()
        ),
        (
            None,
            &BcdValue::Integer(3),
            Some(&[3u8, 0, 0, 0, 0, 0, 0, 0][..])
        )
    );

    // the boot manager, the firmware's, the recovery environment on a ramdisk and its options
    let manager = find(&objects, "{9dea862c-5cdd-4e70-acc1-f32b344d4795}");
    assert_eq!(manager.type_name, "Windows boot manager");
    assert!(!manager.is_default);
    let timeout = manager
        .elements
        .iter()
        .find(|e| e.name == Some("BcdBootMgrInteger_Timeout"))
        .unwrap();
    assert_eq!(timeout.value, BcdValue::Integer(30));
    let firmware = find(&objects, "{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}");
    assert_eq!(firmware.type_name, "firmware boot manager");
    match &firmware.elements[0].value {
        BcdValue::ObjectList(order) => assert_eq!(order.len(), 4),
        other => panic!("{other:?}"),
    }
    let winre = find(&objects, "{733b62e6-f608-11eb-825c-c112f60133ab}");
    assert_eq!(
        winre.device.as_deref(),
        Some("device with options {733b62e7-f608-11eb-825c-c112f60133ab}")
    );
    assert_eq!(
        find(&objects, "{733b62e7-f608-11eb-825c-c112f60133ab}").type_name,
        "device"
    );
    assert_eq!(
        find(&objects, "{6efb52bf-1766-41db-a6b3-0ee5eff72bd7}").type_name,
        "inherited settings for Windows boot loader"
    );
    // firmware entries of another kind of application
    assert_eq!(
        find(&objects, "{733b62de-f608-11eb-825c-c112f60133ab}").type_name,
        "application 0x101fffff"
    );
}
