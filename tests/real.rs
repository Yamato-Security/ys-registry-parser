//! Real hives from regipy's test data (MIT; `tests/fixtures/regipy/`): every key and value,
//! with the transaction logs of the dirty ones, and the deleted keys and values in their free
//! cells. The counts are those yarp reads from the same hives (and recovers from their logs and
//! free cells).
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::{Data, Hive, LogFile, Recovery, Status, decode};

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

fn open(name: &str, logs: &[&str]) -> (Hive, Recovery) {
    let logs: Vec<LogFile> = logs
        .iter()
        .map(|&l| LogFile {
            name: l.to_owned(),
            data: fixture(l),
        })
        .collect();
    Hive::open(fixture(name), &logs).unwrap()
}

/// Keys, values, and how many of each came from the logs.
fn count(hive: &Hive) -> (usize, usize, usize, usize) {
    let (mut keys, mut values, mut replayed_keys, mut replayed_values) = (0, 0, 0, 0);
    for entry in hive.walk() {
        assert_eq!(entry.problems, Vec::<String>::new(), "{}", entry.path);
        keys += 1;
        replayed_keys += usize::from(entry.key.status() == Status::Replayed);
        let (vals, problems) = entry.key.values();
        assert_eq!(problems, Vec::<String>::new(), "{}", entry.path);
        for v in vals {
            assert_eq!(v.read_data().1, None, "{}\\{}", entry.path, v.name());
            values += 1;
            replayed_values += usize::from(v.status() == Status::Replayed);
        }
    }
    (keys, values, replayed_keys, replayed_values)
}

#[test]
fn hives_read_as_they_are() {
    for (name, keys, values) in [
        ("SAM", 65, 70),
        ("SECURITY", 100, 109),
        ("BCD", 132, 103),
        ("NTUSER.DAT", 1812, 4094),
    ] {
        let (hive, recovery) = open(name, &[]);
        assert_eq!(count(&hive), (keys, values, 0, 0), "{name}");
        assert!(!recovery.recovered, "{name}");
    }
    // a dirty hive without its logs is read as it is, and said to be dirty
    let (hive, recovery) = open("SECURITY", &[]);
    assert!(recovery.dirty && hive.header().is_dirty());
    let (hive, _) = open("NTUSER.DAT", &[]);
    assert_eq!(hive.header().name(), "ntuser.dat");
    assert!(!hive.header().is_dirty());
}

#[test]
fn values_of_each_type() {
    let (hive, _) = open("NTUSER.DAT", &[]);
    let value = |key: &str, name: &str| {
        let v = hive.key(key).unwrap().value(name).unwrap();
        (
            v.value_type().name(),
            decode(v.data_type(), &v.data().unwrap()),
        )
    };
    assert_eq!(
        value(r"AppEvents\EventLabels\.Default", ""),
        ("REG_SZ".into(), Data::Text("Default Beep".into()))
    );
    assert_eq!(
        value(
            r"AppEvents\EventLabels\SearchProviderDiscovered",
            "DispFileName"
        ),
        (
            "REG_EXPAND_SZ".into(),
            Data::Text("@ieframe.dll,-12513".into())
        )
    );
    assert_eq!(
        value(
            r"Software\Microsoft\Cryptography\CertificateTemplateCache\Administrator",
            "SupportedCSPs"
        ),
        (
            "REG_MULTI_SZ".into(),
            Data::MultiText(vec![
                "Microsoft Enhanced Cryptographic Provider v1.0".into(),
                "Microsoft Base Cryptographic Provider v1.0".into()
            ])
        )
    );
    assert_eq!(
        value("Console", "ColorTable00"),
        ("REG_DWORD".into(), Data::Number(0))
    );
    assert_eq!(
        value(r"Control Panel\Appearance\New Schemes\0\Sizes\0", "Size #0"),
        ("REG_QWORD".into(), Data::Number(1))
    );
    let mask = hive
        .key(r"control panel\desktop")
        .unwrap()
        .value("userpreferencesmask")
        .unwrap();
    assert_eq!(mask.value_type().name(), "REG_BINARY");
    assert_eq!(
        mask.data().unwrap(),
        [0x90, 0x24, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00]
    );
    let run = hive
        .key(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .unwrap();
    assert_eq!(run.last_written(), 129_779_615_948_377_168);
    assert_eq!(run.value_count(), 1);
}

#[test]
fn dirty_hives_with_their_logs() {
    let (hive, recovery) = open("transactions_NTUSER.DAT", &[]);
    assert!(recovery.dirty && !recovery.recovered);
    assert_eq!(count(&hive), (2590, 4119, 0, 0));
    let (hive, recovery) = open(
        "transactions_NTUSER.DAT",
        &[
            "transactions_ntuser.dat.log1",
            "transactions_ntuser.dat.log2",
        ],
    );
    assert!(recovery.recovered);
    // log2's entries are older than the hive: only log1 is applied
    assert_eq!(recovery.logs_applied, ["transactions_ntuser.dat.log1"]);
    assert_eq!(count(&hive), (3105, 4695, 726, 724));
    assert!(!hive.header().is_dirty());
    let (hive, recovery) = open("UsrClass.dat", &["UsrClass.dat.LOG1", "UsrClass.dat.LOG2"]);
    assert!(recovery.recovered);
    assert_eq!(count(&hive), (6238, 12531, 54, 183));
}

#[test]
fn deleted_keys_and_values() {
    let (hive, _) = open("SAM", &[]);
    let deleted = hive.deleted();
    let keys: Vec<(&str, bool, usize)> = deleted
        .keys
        .iter()
        .map(|k| (k.path.as_str(), k.path_complete, k.values.len()))
        .collect();
    assert_eq!(
        keys,
        [
            (r"SAM\Domains\Builtin\Aliases\Names\Power Users", true, 1),
            (
                r"SAM\Domains\Builtin\Aliases\Names\Network Configuration Operators",
                true,
                1
            ),
            (
                r"SAM\Domains\Builtin\Aliases\Names\Cryptographic Operators",
                true,
                1
            ),
        ]
    );
    assert_eq!(deleted.keys[0].last_written, 130_560_137_964_065_369);
    assert_eq!(deleted.values.len(), 1);

    // deleted keys whose parents were reused: their paths start unknown
    let (hive, _) = open("UsrClass.dat", &[]);
    let deleted = hive.deleted();
    assert_eq!(deleted.keys.len(), 94);
    assert_eq!(
        deleted.keys.iter().map(|k| k.values.len()).sum::<usize>(),
        202
    );
    assert_eq!(deleted.values.len(), 20);
    assert!(
        deleted.keys[0]
            .path
            .starts_with(r"[unknown]\microsoft.windowslive.mail.AppX")
    );
    assert!(!deleted.keys[0].path_complete);

    let (hive, _) = open("NTUSER.DAT", &[]);
    let deleted = hive.deleted();
    assert_eq!((deleted.keys.len(), deleted.values.len()), (0, 29));
}
