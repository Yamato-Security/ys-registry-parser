//! The `UsrClass.dat` of regipy's test data (MIT; `tests/fixtures/regipy/`): its `ShellBags`, as
//! is and with its transaction logs. The keys, their `MRUListEx` order and their items are those
//! libfwsi, Plaso, regipy and dissect.target read from the same hive.
#![allow(clippy::unwrap_used)]

use std::io::Read;

use ys_registry_parser::shellbags::shell_bags;
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

const BAG: &str = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU";

#[test]
fn shell_bags_as_the_hive_is() {
    let hive = Hive::open(fixture("UsrClass.dat"), &[]).unwrap().0;
    let (bags, problems) = shell_bags(&hive).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(bags.len(), 29);
    assert!(bags.iter().all(|b| b.problems.is_empty() && !b.replayed));
    let top: Vec<String> = bags
        .iter()
        .filter(|b| b.parent.is_none())
        .map(|b| b.numbers[0].to_string())
        .collect();
    assert_eq!(top, ["4", "8", "7", "6", "9", "0", "1", "5", "3", "2"]);
    // This PC, then C:, Users and jcloudy under it.
    let path: Vec<(String, Option<u32>, Option<u32>)> = bags[..4]
        .iter()
        .map(|b| (b.key_path(), b.mru_position, b.node_slot))
        .collect();
    assert_eq!(
        path,
        [
            (format!(r"{BAG}\4"), Some(0), Some(7)),
            (format!(r"{BAG}\4\3"), Some(0), None),
            (format!(r"{BAG}\4\3\0"), Some(0), None),
            (format!(r"{BAG}\4\3\0\0"), Some(0), Some(21)),
        ]
    );
    assert_eq!(bags[1].parent, Some(0));
    // The volume item of C: and the time of the key that lists it first.
    assert_eq!(
        bags[1].data.as_deref().unwrap()[..6],
        [0x19, 0, 0x2f, b'C', b':', b'\\']
    );
    assert_eq!(bags[1].parent_last_written, bags[0].last_written.unwrap());
}

#[test]
fn shell_bags_with_the_transaction_logs() {
    let logs = ["UsrClass.dat.LOG1", "UsrClass.dat.LOG2"].map(|name| LogFile {
        name: name.to_owned(),
        data: fixture(name),
    });
    let (hive, recovery) = Hive::open(fixture("UsrClass.dat"), &logs).unwrap();
    assert!(recovery.recovered);
    let (bags, problems) = shell_bags(&hive).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(bags.len(), 38);
    assert_eq!(bags.iter().filter(|b| b.replayed).count(), 24);
    // The logs add a removable drive (value 10) as the second most recent top item.
    let ten = bags
        .iter()
        .find(|b| b.key_path() == format!(r"{BAG}\10"))
        .unwrap();
    assert_eq!(ten.mru_position, Some(1));
    assert!(ten.replayed);
}
